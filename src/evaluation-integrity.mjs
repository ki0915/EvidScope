import {canonical} from './crypto.mjs';

const mismatch=()=>{throw Error('Evaluation projection differs from signed evidence');};

// Call only after authenticating every supplied payload through the tenant's
// final signed checkpoint, and keep this comparison and later use in one
// SQLite snapshot/transaction.
export function checkEvaluationProjection(db,tenant,signedEvaluations){
 if(!Array.isArray(signedEvaluations))throw TypeError('Signed evaluations must be an array');
 const rows=db.prepare('SELECT action_id,version,body FROM evaluations WHERE tenant=? ORDER BY id').all(tenant);
 if(rows.length!==signedEvaluations.length)mismatch();
 for(let index=0;index<rows.length;index++){
  const signed=signedEvaluations[index],row=rows[index];let projected;
  try{projected=JSON.parse(row.body);}catch{mismatch();}
  if(!signed||typeof signed!=='object'||row.action_id!==signed.actionId||row.version!==signed.version||canonical(projected)!==canonical(signed))mismatch();
 }
 return {valid:true,evaluations:signedEvaluations.length};
}
