import {canonical} from './crypto.mjs';

const objectTypes=new Set(['catalog','system','assessment','governance_task','asset','case','case_decision','rule','exception','retention_policy','retention_hold','retention_plan','supplier_bundle','finance_report','assistance_profile','assistance_package','assistance_run','assistance_review','identity_access']);

export const isSignedObjectType=type=>objectTypes.has(type);

// The ledger stores payloads, while these two types have a distinct SQL key.
export function signedObjectProjection(row){
 if(!objectTypes.has(row.type))return null;
 const id=row.type==='catalog'?'current':row.type==='assistance_profile'?`${row.payload.id}@${row.payload.version}`:row.payload.id;
 if(!id)throw Error('Invalid signed object identity');
 return {key:canonical([row.type,id]),type:row.type,id,payload:row.payload};
}

// Caller must authenticate records through the final signed checkpoint before
// calling, and keep records and SQL reads in the same snapshot/transaction.
// This compares projections only; it does not independently authenticate records.
export function checkObjectProjection(db,tenant,verifiedRecords){
 const original=new Map();
 for(const row of verifiedRecords){
  if(row.tenant!==tenant)throw Error('Object evidence tenant mismatch');
  const value=signedObjectProjection(row);if(value!==null)original.set(value.key,canonical(value.payload));
 }
 const projected=db.prepare('SELECT type,id,body FROM objects WHERE tenant=?').all(tenant);
 if(projected.length!==original.size||projected.some(row=>original.get(canonical([row.type,row.id]))!==canonical(JSON.parse(row.body))))throw Error('Object projection differs from signed evidence');
 return {valid:true,objects:projected.length};
}
