import {canonical} from './crypto.mjs';

const mismatch=()=>{throw Error('Evaluation projection differs from signed evidence');};

// Call only after authenticating every supplied payload through the tenant's
// final signed checkpoint, and keep this comparison and later use in one
// SQLite snapshot/transaction.
// out (optional): receives lastId, the id of the last verified row, where a later delta check of appended rows starts
// (Store._verifyActionDelta). It is kept out of the result, which /api/integrity serves.
export function checkEvaluationProjection(db,tenant,signedEvaluations,out){
 if(!Array.isArray(signedEvaluations))throw TypeError('Signed evaluations must be an array');
 const rows=db.prepare('SELECT id,action_id,version,body FROM evaluations WHERE tenant=? ORDER BY id').all(tenant);
 if(rows.length!==signedEvaluations.length)mismatch();
 for(let index=0;index<rows.length;index++){
  const signed=signedEvaluations[index],row=rows[index];let projected;
  try{projected=JSON.parse(row.body);}catch{mismatch();}
  if(!signed||typeof signed!=='object'||row.action_id!==signed.actionId||row.version!==signed.version||canonical(projected)!==canonical(signed))mismatch();
 }
 if(out)out.lastId=rows.length?rows.at(-1).id:0;
 return {valid:true,evaluations:signedEvaluations.length};
}
