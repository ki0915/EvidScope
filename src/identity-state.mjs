import {createHash} from 'node:crypto';
import {digest,verifyCheckpoint} from './crypto.mjs';

const zero='0'.repeat(64),rowBytes=64*1024;

// This is an authentication cache, not a fresh integrity report for every old
// ledger byte. A new instance verifies the full chain; later reads verify its
// cached anchor and every appended record before publishing new access state.
export function createIdentityState(store){
 const cache=new Map(),db=store.db;
 const checkpointQuery=db.prepare(`SELECT length(CAST(body AS BLOB)) AS bytes,
  CASE WHEN length(CAST(body AS BLOB))<=4096 THEN body ELSE NULL END AS body
  FROM checkpoints WHERE tenant=?`);
 const columns=`seq,hash,length(CAST(body AS BLOB)) AS bytes,
  json_extract(body,'$.tenant') AS record_tenant,json_extract(body,'$.seq') AS record_seq,
  json_extract(body,'$.previous') AS previous,json_extract(body,'$.type') AS type,
  CASE WHEN length(CAST(body AS BLOB))<=${rowBytes} THEN body ELSE NULL END AS body`;
 const anchorQuery=db.prepare(`SELECT ${columns} FROM ledger WHERE tenant=? AND seq=?`);
 const suffixQuery=db.prepare(`SELECT ${columns} FROM ledger WHERE tenant=? AND seq>? ORDER BY seq`);
 const headQuery=db.prepare('SELECT seq,hash FROM ledger WHERE tenant=? ORDER BY seq DESC LIMIT 1');
 const chunkQuery=db.prepare('SELECT substr(CAST(body AS BLOB),?,?) AS chunk FROM ledger WHERE tenant=? AND seq=?');
 function hashRow(row,tenant){
  if(row.record_tenant!==tenant||row.record_seq!==row.seq)throw Error('Identity ledger SQL tenant or sequence mismatch');
  let hash;
  if(row.body!==null)hash=digest(row.body);
  else{
   const hasher=createHash('sha256');
   for(let offset=1;offset<=row.bytes;offset+=rowBytes){const chunk=chunkQuery.get(offset,rowBytes,tenant,row.seq)?.chunk;if(!chunk||chunk.length!==Math.min(rowBytes,row.bytes-offset+1))throw Error('Identity ledger chunk missing');hasher.update(chunk);}
   hash=hasher.digest('hex');
  }
  if(hash!==row.hash)throw Error('Identity ledger record digest mismatch');
 }
 return function state(binding){
  const tenant=binding.tenant,old=cache.get(tenant);let next;
  // SAVEPOINT also works inside the access-update transaction; no nested BEGIN.
  // All reads are synchronous and see one SQLite snapshot.
  db.exec('SAVEPOINT evidscope_identity_read');
  try{
   const saved=checkpointQuery.get(tenant),head=headQuery.get(tenant);
   if(saved&&!saved.body)throw Error('Identity checkpoint exceeds size limit');
   const checkpoint=saved?JSON.parse(saved.body):{tenant,count:0,head:zero};
   if(saved)verifyCheckpoint(checkpoint,store.publicKey);
   if(checkpoint.tenant!==tenant||!Number.isSafeInteger(checkpoint.count)||checkpoint.count<0||!/^[a-f0-9]{64}$/.test(checkpoint.head))throw Error('Identity checkpoint tenant or count invalid');
   if(checkpoint.count===0&&head||(head?.seq??0)!==checkpoint.count||(head?.hash??zero)!==checkpoint.head)throw Error('Identity ledger head or checkpoint mismatch');
   if(old&&(checkpoint.count<old.count||checkpoint.count===old.count&&checkpoint.head!==old.head||old.signed&&!saved))throw Error('Identity checkpoint rollback or replacement');
   if(old?.count){
    const anchor=anchorQuery.get(tenant,old.count);
    if(!anchor||anchor.hash!==old.head)throw Error('Identity cached anchor missing or changed');
    hashRow(anchor,tenant);
   }
   if(old&&checkpoint.count===old.count)next={...old,signed:!!saved};
   else{
    const states=new Map(old?.states),start=old?.count||0;let sequence=start,previous=old?.head||zero;
    for(const row of suffixQuery.iterate(tenant,start)){
     if(row.seq!==++sequence||row.previous!==previous)throw Error('Identity ledger sequence or previous hash mismatch');
     hashRow(row,tenant);previous=row.hash;
     if(row.type==='identity_access'){
      if(row.body===null)throw Error('Identity access record exceeds size limit');
      const value=JSON.parse(row.body).payload;
      if(!value||typeof value.id!=='string'||!value.id||!Number.isSafeInteger(value.epoch)||value.epoch<0||typeof value.disabled!=='boolean')throw Error('Invalid signed identity access state');
      states.set(value.id,value);
     }
    }
    if(sequence!==checkpoint.count||previous!==checkpoint.head)throw Error('Identity ledger truncated or inconsistent checkpoint');
    next={count:checkpoint.count,head:checkpoint.head,signed:!!saved,states};
   }
   db.exec('RELEASE evidscope_identity_read');
  }catch(error){db.exec('ROLLBACK TO evidscope_identity_read');db.exec('RELEASE evidscope_identity_read');throw error;}
  cache.set(tenant,next);
  return structuredClone(next.states.get(binding.id)||{id:binding.id,epoch:0,disabled:false});
 };
}
