import {canonical} from './crypto.mjs';

const mismatch=detail=>{throw Error(`Development projection differs from signed evidence${detail?`: ${detail}`:''}`);};
const identity=(source,eventId)=>canonical([source,eventId]);

// Authenticated events must come from a ledger verified through its final
// checkpoint. Keep this comparison and subsequent query use in one transaction.
export function checkDevelopmentRunProjection(db,tenant,authenticatedEvents){
 if(typeof tenant!=='string'||!tenant||!Array.isArray(authenticatedEvents))throw TypeError('Tenant and authenticated development events are required');
 const table=db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='development_run_events'").get();
 if(!table){if(authenticatedEvents.length)mismatch('missing table');return {valid:true,developmentEvents:0};}
 const expected=new Map();
 for(const event of authenticatedEvents){
  if(!event||typeof event!=='object'||Array.isArray(event)||event.tenant!==tenant||typeof event.source!=='string'||typeof event.eventId!=='string')mismatch('invalid authenticated event');
  const key=identity(event.source,event.eventId);if(expected.has(key))mismatch('duplicate authenticated event identity');expected.set(key,event);
 }
 const rows=db.prepare('SELECT tenant,source,event_id,run_id,occurred,received,fingerprint,body FROM development_run_events WHERE tenant=?').all(tenant);
 if(rows.length!==expected.size)mismatch('row count');
 for(const row of rows){
  const signed=expected.get(identity(row.source,row.event_id));if(!signed)mismatch('unsigned or re-keyed row');
  let body;try{body=JSON.parse(row.body);}catch{mismatch('invalid body JSON');}
  if(canonical(body)!==canonical(signed))mismatch('body');
  if(canonical([row.tenant,row.source,row.event_id,row.run_id,row.occurred,row.received,row.fingerprint])!==canonical([signed.tenant,signed.source,signed.eventId,signed.runId,signed.occurredAt,signed.receivedAt,signed.fingerprint]))mismatch('index');
 }
 return {valid:true,developmentEvents:rows.length};
}
